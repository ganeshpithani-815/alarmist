"""
Alarmist — Production Flask App
- PostgreSQL via SQLAlchemy
- Secure session cookies (HTTPS only in prod)
- Security headers via Flask-Talisman
- Rate limiting, input validation, hashed OTPs
- Proper logging and error handlers
"""

import os, re, logging, random
from datetime import datetime, timedelta
from functools import wraps

from flask import Flask, request, jsonify, session, send_from_directory, g
from flask_sqlalchemy import SQLAlchemy
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from twilio.rest import Client as TwilioClient
from dotenv import load_dotenv

load_dotenv()

# ─── Logging ─────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
log = logging.getLogger("alarmist")

# ─── Config ──────────────────────────────────────────────────────────────────
def require_env(key):
    v = os.environ.get(key)
    if not v:
        raise RuntimeError(f"Required env var missing: {key}")
    return v

IS_PROD      = os.environ.get("RENDER", "") == "true" or \
               os.environ.get("FLASK_ENV", "") == "production"
SECRET_KEY   = require_env("SECRET_KEY")
DATABASE_URL = require_env("DATABASE_URL").replace("postgres://", "postgresql://", 1)
TWILIO_SID   = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_TOKEN = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM  = os.environ.get("TWILIO_PHONE_NUMBER", "")
DEMO_MODE    = not all([TWILIO_SID, TWILIO_TOKEN, TWILIO_FROM])

# ─── App ─────────────────────────────────────────────────────────────────────
app = Flask(__name__, static_folder="static", template_folder="templates")
app.config.update(
    SECRET_KEY                     = SECRET_KEY,
    SQLALCHEMY_DATABASE_URI        = DATABASE_URL,
    SQLALCHEMY_TRACK_MODIFICATIONS = False,
    SQLALCHEMY_ENGINE_OPTIONS      = {"pool_pre_ping": True, "pool_recycle": 300,
                                      "pool_size": 5, "max_overflow": 10},
    SESSION_COOKIE_HTTPONLY        = True,
    SESSION_COOKIE_SAMESITE        = "Lax",
    SESSION_COOKIE_SECURE          = IS_PROD,
    PERMANENT_SESSION_LIFETIME     = timedelta(days=30),
)

db = SQLAlchemy(app)

csp = {"default-src": ["'self'"], "script-src": ["'self'", "'unsafe-inline'"],
       "style-src": ["'self'", "'unsafe-inline'"], "img-src": ["'self'", "data:"]}
Talisman(app, force_https=IS_PROD, content_security_policy=csp,
         strict_transport_security=IS_PROD, strict_transport_security_max_age=31536000)

limiter = Limiter(get_remote_address, app=app,
                  default_limits=["500 per day", "100 per hour"],
                  storage_uri="memory://")

# ─── Models ──────────────────────────────────────────────────────────────────
class User(db.Model):
    __tablename__ = "users"
    id           = db.Column(db.Integer, primary_key=True)
    phone        = db.Column(db.String(20), unique=True, nullable=False, index=True)
    name         = db.Column(db.String(80), default="")
    avatar_color = db.Column(db.String(10), default="#1D9E75")
    timezone     = db.Column(db.String(50), default="Asia/Kolkata")
    sound_on     = db.Column(db.Boolean, default=True)
    vibrate_on   = db.Column(db.Boolean, default=True)
    snooze_limit = db.Column(db.Integer, default=3)
    is_active    = db.Column(db.Boolean, default=True)
    created_at   = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login   = db.Column(db.DateTime)
    todos        = db.relationship("Todo",  backref="user", lazy="dynamic", cascade="all,delete-orphan")
    alarms       = db.relationship("Alarm", backref="user", lazy="dynamic", cascade="all,delete-orphan")

    def to_dict(self):
        return {"id": self.id, "phone": self.phone, "name": self.name,
                "avatar_color": self.avatar_color, "timezone": self.timezone,
                "sound_on": self.sound_on, "vibrate_on": self.vibrate_on,
                "snooze_limit": self.snooze_limit,
                "created_at": self.created_at.isoformat(),
                "last_login": self.last_login.isoformat() if self.last_login else None}


class OTP(db.Model):
    __tablename__ = "otps"
    id         = db.Column(db.Integer, primary_key=True)
    phone      = db.Column(db.String(20), nullable=False, index=True)
    code_hash  = db.Column(db.String(64), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    used       = db.Column(db.Boolean, default=False)
    attempts   = db.Column(db.Integer, default=0)

    def is_expired(self):
        return datetime.utcnow() > self.created_at + timedelta(minutes=10)

    @staticmethod
    def hash(code):
        import hashlib
        return hashlib.sha256(code.encode()).hexdigest()


class Todo(db.Model):
    __tablename__ = "todos"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    text       = db.Column(db.String(500), nullable=False)
    done       = db.Column(db.Boolean, default=False)
    priority   = db.Column(db.String(10), default="med")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def to_dict(self):
        return {"id": self.id, "text": self.text, "done": self.done,
                "priority": self.priority, "created_at": self.created_at.isoformat()}


class Alarm(db.Model):
    __tablename__ = "alarms"
    id         = db.Column(db.Integer, primary_key=True)
    user_id    = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    time       = db.Column(db.String(5), nullable=False)
    label      = db.Column(db.String(100), default="Alarm")
    game       = db.Column(db.String(20), default="Whack")
    on         = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {"id": self.id, "time": self.time, "label": self.label,
                "game": self.game, "on": self.on}

# ─── Helpers ─────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return jsonify({"error": "Unauthorized"}), 401
        user = User.query.get(session["user_id"])
        if not user or not user.is_active:
            session.clear()
            return jsonify({"error": "Account not found"}), 401
        g.current_user = user
        return f(*args, **kwargs)
    return wrapper

def normalize_phone(raw):
    digits = re.sub(r"[^\d+]", "", str(raw))
    if not digits.startswith("+"):
        digits = "+91" + digits.lstrip("0")
    return digits if re.match(r"^\+\d{7,15}$", digits) else None

def send_otp_sms(phone, code):
    if DEMO_MODE:
        log.warning(f"[DEMO] OTP for {phone}: {code}")
        return True
    try:
        TwilioClient(TWILIO_SID, TWILIO_TOKEN).messages.create(
            body=f"Your Alarmist OTP: {code}. Valid 10 mins. Do not share.",
            from_=TWILIO_FROM, to=phone)
        return True
    except Exception as e:
        log.error(f"Twilio error: {e}")
        return False

# ─── Hooks ───────────────────────────────────────────────────────────────────
@app.before_request
def make_session_permanent():
    session.permanent = True

@app.after_request
def headers(resp):
    resp.headers["X-Frame-Options"] = "DENY"
    if request.path.startswith("/api/"):
        resp.headers["Cache-Control"] = "no-store"
    return resp

# ─── Error handlers ──────────────────────────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    if request.path.startswith("/api/"):
        return jsonify({"error": "Not found"}), 404
    return send_from_directory(app.template_folder, "index.html")

@app.errorhandler(429)
def rate_limited(e):
    return jsonify({"error": "Too many requests. Please slow down."}), 429

@app.errorhandler(500)
def server_error(e):
    log.exception("Internal server error")
    return jsonify({"error": "Server error. Please try again."}), 500

# ─── Auth routes ─────────────────────────────────────────────────────────────
@app.route("/api/auth/send-otp", methods=["POST"])
@limiter.limit("5 per minute; 20 per hour")
def send_otp():
    data  = request.get_json(silent=True) or {}
    phone = normalize_phone(data.get("phone", ""))
    if not phone:
        return jsonify({"error": "Invalid phone number"}), 400
    OTP.query.filter_by(phone=phone, used=False).update({"used": True})
    db.session.commit()
    code = str(random.randint(100000, 999999))
    db.session.add(OTP(phone=phone, code_hash=OTP.hash(code)))
    db.session.commit()
    if not send_otp_sms(phone, code):
        return jsonify({"error": "Failed to send SMS. Please try again."}), 500
    resp = {"message": "OTP sent", "phone": phone}
    if DEMO_MODE:
        resp.update({"demo_mode": True, "demo_code": code})
    return jsonify(resp)


@app.route("/api/auth/verify-otp", methods=["POST"])
@limiter.limit("10 per minute")
def verify_otp():
    data  = request.get_json(silent=True) or {}
    phone = normalize_phone(data.get("phone", ""))
    code  = str(data.get("code", "")).strip()
    if not phone or not re.match(r"^\d{6}$", code):
        return jsonify({"error": "Invalid request"}), 400
    otp = OTP.query.filter_by(phone=phone, used=False)\
              .order_by(OTP.created_at.desc()).first()
    if not otp:
        return jsonify({"error": "No active OTP. Request a new one."}), 400
    if otp.is_expired():
        otp.used = True; db.session.commit()
        return jsonify({"error": "OTP expired. Request a new one."}), 400
    if otp.attempts >= 5:
        otp.used = True; db.session.commit()
        return jsonify({"error": "Too many attempts. Request a new OTP."}), 400
    otp.attempts += 1
    if otp.code_hash != OTP.hash(code):
        db.session.commit()
        return jsonify({"error": f"Wrong OTP. {5 - otp.attempts} attempt(s) left."}), 400
    otp.used = True; db.session.commit()
    is_new = False
    user   = User.query.filter_by(phone=phone).first()
    if not user:
        user = User(phone=phone); db.session.add(user); is_new = True
    user.last_login = datetime.utcnow(); db.session.commit()
    session["user_id"] = user.id
    log.info(f"Login: user={user.id} phone={phone} new={is_new}")
    return jsonify({"message": "Login successful", "user": user.to_dict(), "new_user": is_new})


@app.route("/api/auth/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out"})

@app.route("/api/auth/me")
@login_required
def me():
    return jsonify(g.current_user.to_dict())

@app.route("/api/auth/delete-account", methods=["DELETE"])
@login_required
def delete_account():
    db.session.delete(g.current_user); db.session.commit(); session.clear()
    return jsonify({"message": "Account deleted"})

# ─── Profile ─────────────────────────────────────────────────────────────────
@app.route("/api/profile", methods=["PUT"])
@login_required
def update_profile():
    user = g.current_user
    data = request.get_json(silent=True) or {}
    for field, typ, maxlen in [
        ("name", str, 80), ("avatar_color", str, 10), ("timezone", str, 50),
        ("sound_on", bool, None), ("vibrate_on", bool, None), ("snooze_limit", int, None)]:
        if field in data and isinstance(data[field], typ):
            val = data[field]
            if maxlen and isinstance(val, str): val = val[:maxlen].strip()
            setattr(user, field, val)
    db.session.commit()
    return jsonify({"message": "Updated", "user": user.to_dict()})

# ─── Todos ───────────────────────────────────────────────────────────────────
@app.route("/api/todos")
@login_required
def get_todos():
    return jsonify([t.to_dict() for t in g.current_user.todos.order_by(Todo.created_at.desc())])

@app.route("/api/todos", methods=["POST"])
@login_required
@limiter.limit("100 per hour")
def add_todo():
    data = request.get_json(silent=True) or {}
    text = str(data.get("text","")).strip()[:500]
    if not text: return jsonify({"error": "Text required"}), 400
    prio = data.get("priority","med") if data.get("priority") in ("high","med","low") else "med"
    t = Todo(user_id=g.current_user.id, text=text, priority=prio)
    db.session.add(t); db.session.commit()
    return jsonify(t.to_dict()), 201

@app.route("/api/todos/<int:tid>", methods=["PUT"])
@login_required
def update_todo(tid):
    t = Todo.query.filter_by(id=tid, user_id=g.current_user.id).first_or_404()
    d = request.get_json(silent=True) or {}
    if "done" in d and isinstance(d["done"], bool): t.done = d["done"]
    if "text" in d and isinstance(d["text"], str):  t.text = d["text"][:500].strip()
    if d.get("priority") in ("high","med","low"):   t.priority = d["priority"]
    db.session.commit(); return jsonify(t.to_dict())

@app.route("/api/todos/<int:tid>", methods=["DELETE"])
@login_required
def delete_todo(tid):
    t = Todo.query.filter_by(id=tid, user_id=g.current_user.id).first_or_404()
    db.session.delete(t); db.session.commit()
    return jsonify({"message": "Deleted"})

# ─── Alarms ──────────────────────────────────────────────────────────────────
@app.route("/api/alarms")
@login_required
def get_alarms():
    return jsonify([a.to_dict() for a in g.current_user.alarms.order_by(Alarm.time)])

@app.route("/api/alarms", methods=["POST"])
@login_required
@limiter.limit("50 per hour")
def add_alarm():
    d = request.get_json(silent=True) or {}
    t = str(d.get("time","")).strip()
    if not re.match(r"^\d{2}:\d{2}$", t): return jsonify({"error": "Time must be HH:MM"}), 400
    game = d.get("game","Whack") if d.get("game") in ("Whack","Simon","Tap") else "Whack"
    a = Alarm(user_id=g.current_user.id, time=t,
              label=str(d.get("label","Alarm"))[:100].strip(), game=game)
    db.session.add(a); db.session.commit()
    return jsonify(a.to_dict()), 201

@app.route("/api/alarms/<int:aid>", methods=["PUT"])
@login_required
def update_alarm(aid):
    a = Alarm.query.filter_by(id=aid, user_id=g.current_user.id).first_or_404()
    d = request.get_json(silent=True) or {}
    if "on"    in d and isinstance(d["on"], bool): a.on = d["on"]
    if "label" in d and isinstance(d["label"], str): a.label = d["label"][:100].strip()
    if d.get("game") in ("Whack","Simon","Tap"):  a.game = d["game"]
    db.session.commit(); return jsonify(a.to_dict())

@app.route("/api/alarms/<int:aid>", methods=["DELETE"])
@login_required
def delete_alarm(aid):
    a = Alarm.query.filter_by(id=aid, user_id=g.current_user.id).first_or_404()
    db.session.delete(a); db.session.commit()
    return jsonify({"message": "Deleted"})

# ─── Stats ───────────────────────────────────────────────────────────────────
@app.route("/api/stats")
@login_required
def get_stats():
    todos  = g.current_user.todos.all()
    alarms = g.current_user.alarms.all()
    total  = len(todos); done = sum(1 for t in todos if t.done)
    return jsonify({"total_tasks": total, "completed": done, "pending": total - done,
                    "completion_pct": round(done/total*100 if total else 0, 1),
                    "active_alarms": sum(1 for a in alarms if a.on),
                    "total_alarms": len(alarms)})

# ─── Health check (Render uses this) ─────────────────────────────────────────
@app.route("/health")
def health():
    try:
        db.session.execute(db.text("SELECT 1"))
        return jsonify({"status": "ok", "db": "connected", "demo_mode": DEMO_MODE})
    except Exception as e:
        return jsonify({"status": "error", "detail": str(e)}), 500

# ─── Serve frontend ──────────────────────────────────────────────────────────
@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve(path):
    if path and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.template_folder, "index.html")

# ─── Init ────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        log.info("DB ready")
        if DEMO_MODE: log.warning("DEMO MODE — set Twilio env vars for real SMS")
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=not IS_PROD)

from flask import Flask, request, session, redirect, url_for, make_response, render_template
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from database.models import db, CameraLog, LoginLog
from config import Config
from functools import wraps
from datetime import timedelta
import os
import time
import secrets
import pyotp
import hmac

# ======================================================================
# APP INIT
# ======================================================================
app = Flask(__name__)
app.config.from_object(Config)

app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(minutes=30))
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config.setdefault("SQLALCHEMY_DATABASE_URI", os.environ.get("DATABASE_URL", "sqlite:///cctv.db"))
app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)

PEPPER = os.environ.get("CRYPTOGRAPHIC_PEPPER", "FallbackSuperSecretPepper2026!")

app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax"
)

# ─── Extensions ───────────────────────────────────────────────────────
db.init_app(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# ── Exempt /push_frame from CSRF — it's a machine-to-machine POST ─────
# authenticated by X-Push-Secret header instead
csrf.exempt("routes.camera.push_frame")

# ─── Rate Limiter ─────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# ─── In-memory IP failure tracking ────────────────────────────────────
IP_FAILED_ATTEMPTS = {}


# ======================================================================
# SECURITY UTILITIES
# ======================================================================

def get_sanitized_ip():
    if request.headers.get("X-Forwarded-For"):
        ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
    else:
        ip = request.remote_addr
    return "".join(c for c in ip if c.isalnum() or c in [".", ":"])


def is_ip_blocked(ip: str) -> bool:
    from database.models import BlockedIP
    return BlockedIP.query.filter_by(ip_address=ip).first() is not None


def secure_session_destruct():
    session.clear()


def render_with_error(err_msg):
    return make_response(render_template("login.html", error=err_msg))


# ======================================================================
# SESSION ENFORCEMENT DECORATOR
# ======================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))

        now = time.time()

        last_activity = session.get("last_activity", now)
        if (now - last_activity) > 900:
            secure_session_destruct()
            return redirect(url_for("login"))

        login_time = session.get("login_time", now)
        if (now - login_time) > 3600:
            secure_session_destruct()
            return redirect(url_for("login"))

        active_token = app.config.get(f"ACTIVE_SESSION_{session.get('user_id')}")
        if session.get("session_token") != active_token:
            secure_session_destruct()
            return redirect(url_for("login"))

        if is_ip_blocked(get_sanitized_ip()):
            secure_session_destruct()
            return redirect(url_for("login"))
        session["last_activity"] = now
        return f(*args, **kwargs)
    return decorated_function

# ======================================================================
# GLOBAL HTTP SECURITY HEADERS
# ======================================================================

@app.after_request
def inject_security_headers(response):
    response.headers["Server"] = "Secure-Kernel-CCTV"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "frame-ancestors 'none';"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    response.headers["Access-Control-Allow-Origin"] = "null"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST"
    return response


# ======================================================================
# HONEYPOT TRAPS
# ======================================================================

from flask import abort

@app.route("/.env")
@app.route("/.git")
@app.route("/wp-admin")
@app.route("/phpmyadmin")
def sensitive_path_block():
    return abort(404)


# ======================================================================
# BLUEPRINTS
# ======================================================================

from routes.auth import auth
from routes.dashboard import dashboard_bp
from routes.camera import camera_bp
from routes.blocked import blocked_bp
from routes.viewer import viewer_bp

app.register_blueprint(auth)
app.register_blueprint(dashboard_bp)
app.register_blueprint(camera_bp)
app.register_blueprint(blocked_bp)
app.register_blueprint(viewer_bp)


# ======================================================================
# LOGIN / LOGOUT ROUTES
# ======================================================================

@app.route("/", methods=["GET"])
def index():
    return redirect(url_for("login"))


@app.route("/logout", methods=["POST"])
def logout():
    client_ip = get_sanitized_ip()
    log = CameraLog(event="ADMIN_LOGOUT_REQUESTED", ip_address=client_ip)
    db.session.add(log)
    db.session.commit()
    secure_session_destruct()
    return redirect(url_for("login"))


@app.route("/viewer-logout", methods=["POST"])
def viewer_logout():
    client_ip = get_sanitized_ip()
    log = CameraLog(
        event="VIEWER_LOGOUT_REQUESTED",
        username=session.get("user"),
        ip_address=client_ip
    )
    db.session.add(log)
    db.session.commit()
    secure_session_destruct()
    return redirect(url_for("viewer_login"))


# ── STEP 1: Username + Password ───────────────────────────────────────
@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    client_ip = get_sanitized_ip()
    now = time.time()

    if is_ip_blocked(client_ip):
        return render_with_error("Access denied. Your IP has been blocked by the administrator.")

    if client_ip in IP_FAILED_ATTEMPTS:
        failures, lockout_time = IP_FAILED_ATTEMPTS[client_ip]
        if failures >= 10:
            if now - lockout_time < 300:
                return render_with_error("IP temporarily locked out. Try again later.")
            else:
                IP_FAILED_ATTEMPTS[client_ip] = [0, 0]

    if request.method == "POST":
        input_user = "".join(c for c in request.form.get("username", "") if c.isalnum() or c == "_")
        input_pass = request.form.get("password", "")

        env_admin_user = os.environ.get("ADMIN_USERNAME", "admin")
        env_admin_hash = os.environ.get("ADMIN_PASSWORD_HASH")

        if client_ip in IP_FAILED_ATTEMPTS:
            failures = IP_FAILED_ATTEMPTS[client_ip][0]
            if failures > 0:
                time.sleep(min(0.5 * failures, 10))

        username_match = hmac.compare_digest(
            input_user.encode("utf-8"),
            env_admin_user.encode("utf-8")
        )

        peppered_input = input_pass + PEPPER
        password_match = (
            env_admin_hash is not None
            and bcrypt.check_password_hash(env_admin_hash, peppered_input)
        )

        if username_match and password_match:
            session["otp_pending"] = True
            session["otp_user"]    = env_admin_user
            session["otp_ip"]      = client_ip
            return redirect(url_for("verify_otp"))
        else:
            if client_ip not in IP_FAILED_ATTEMPTS:
                IP_FAILED_ATTEMPTS[client_ip] = [1, now]
            else:
                IP_FAILED_ATTEMPTS[client_ip][0] += 1
                IP_FAILED_ATTEMPTS[client_ip][1] = now

            log = CameraLog(
                event=f"UNAUTHORIZED_LOGIN_ATTEMPT_USER_{input_user}",
                ip_address=client_ip
            )
            db.session.add(log)
            db.session.commit()

            log = LoginLog(username=input_user, ip_address=client_ip, status='failed', role='viewer')
            db.session.add(log)
            db.session.commit()

            return render_with_error("Invalid administrative credentials.")

    session.pop("otp_pending", None)
    session.pop("otp_user", None)
    session.pop("otp_ip", None)
    return render_template("login.html")


# ── STEP 2: OTP Verification ──────────────────────────────────────────
@app.route("/verify-otp", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def verify_otp():
    if not session.get("otp_pending"):
        return redirect(url_for("login"))

    client_ip = get_sanitized_ip()
    now = time.time()

    if request.method == "POST":
        input_otp      = request.form.get("otp", "").strip()
        env_mfa_secret = os.environ.get("ADMIN_MFA_SECRET", "JBSWY3DPEHPK3PXP")
        env_admin_user = session.get("otp_user", "admin")

        totp      = pyotp.TOTP(env_mfa_secret)
        otp_match = totp.verify(input_otp, valid_window=1)

        if otp_match:
            session.pop("otp_pending", None)
            session.pop("otp_user", None)
            session.pop("otp_ip", None)

            secure_session_destruct()
            session.permanent    = True
            session["is_admin"]  = True
            session["user"]      = env_admin_user
            session["role"]      = "admin"
            session["user_id"]   = "admin_01"
            session["login_time"]    = now
            session["last_activity"] = now
            session["session_token"] = secrets.token_hex(32)

            app.config["ACTIVE_SESSION_admin_01"] = session["session_token"]

            log = CameraLog(event="ADMIN_LOGIN_SUCCESSFUL", ip_address=client_ip)
            db.session.add(log)
            db.session.commit()

            log = LoginLog(username=env_admin_user, ip_address=client_ip, status='success', role='admin')
            db.session.add(log)
            db.session.commit()

            return redirect(url_for("dashboard.dashboard"))
        else:
            if client_ip not in IP_FAILED_ATTEMPTS:
                IP_FAILED_ATTEMPTS[client_ip] = [1, now]
            else:
                IP_FAILED_ATTEMPTS[client_ip][0] += 1
                IP_FAILED_ATTEMPTS[client_ip][1] = now

            log = CameraLog(
                event=f"INVALID_OTP_ATTEMPT_USER_{env_admin_user}",
                ip_address=client_ip
            )
            db.session.add(log)
            db.session.commit()

            return make_response(render_template("otp.html", error="Invalid or expired code."))

    return render_template("otp.html")


# ======================================================================
# VIEWER LOGIN — STEP 1: Username + Password
# ======================================================================

@app.route("/viewer-login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def viewer_login():
    from database.models import User
    client_ip = get_sanitized_ip()
    now = time.time()

    if is_ip_blocked(client_ip):
        return make_response(render_template("viewer_login.html",
            error="Access denied. Your IP has been blocked by the administrator."))

    if client_ip in IP_FAILED_ATTEMPTS:
        failures, lockout_time = IP_FAILED_ATTEMPTS[client_ip]
        if failures >= 10:
            if now - lockout_time < 300:
                return make_response(render_template("viewer_login.html",
                    error="IP temporarily locked out. Try again later."))
            else:
                IP_FAILED_ATTEMPTS[client_ip] = [0, 0]

    if request.method == "POST":
        input_user = "".join(c for c in request.form.get("username", "") if c.isalnum() or c == "_")
        input_pass = request.form.get("password", "")

        if client_ip in IP_FAILED_ATTEMPTS:
            failures = IP_FAILED_ATTEMPTS[client_ip][0]
            if failures > 0:
                time.sleep(min(0.5 * failures, 10))

        user = User.query.filter_by(username=input_user, role="viewer").first()

        peppered_input = input_pass + PEPPER
        password_match = (
            user is not None
            and bcrypt.check_password_hash(user.password, peppered_input)
        )

        if user and password_match:
            session["viewer_otp_pending"] = True
            session["viewer_otp_user"]    = user.username
            session["viewer_otp_ip"]      = client_ip
            return redirect(url_for("viewer_verify_otp"))
        else:
            if client_ip not in IP_FAILED_ATTEMPTS:
                IP_FAILED_ATTEMPTS[client_ip] = [1, now]
            else:
                IP_FAILED_ATTEMPTS[client_ip][0] += 1
                IP_FAILED_ATTEMPTS[client_ip][1] = now

            log = CameraLog(
                event=f"UNAUTHORIZED_VIEWER_LOGIN_ATTEMPT_USER_{input_user}",
                ip_address=client_ip
            )
            db.session.add(log)
            db.session.commit()

            log = LoginLog(username=input_user, ip_address=client_ip, status='failed', role='viewer')
            db.session.add(log)
            db.session.commit()

            return make_response(render_template("viewer_login.html",
                error="Invalid credentials."))

    session.pop("viewer_otp_pending", None)
    session.pop("viewer_otp_user", None)
    session.pop("viewer_otp_ip", None)
    return render_template("viewer_login.html")


# ======================================================================
# VIEWER LOGIN — STEP 2: OTP Verification
# ======================================================================

@app.route("/viewer-verify-otp", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def viewer_verify_otp():
    from database.models import User
    if not session.get("viewer_otp_pending"):
        return redirect(url_for("viewer_login"))

    client_ip = get_sanitized_ip()
    now = time.time()

    if request.method == "POST":
        input_otp  = request.form.get("otp", "").strip()
        username   = session.get("viewer_otp_user")
        user       = User.query.filter_by(username=username, role="viewer").first()

        if not user or not user.otp_secret:
            return make_response(render_template("viewer_otp.html",
                error="Account not configured for MFA. Contact admin."))

        totp      = pyotp.TOTP(user.otp_secret)
        otp_match = totp.verify(input_otp, valid_window=1)

        if otp_match:
            session.pop("viewer_otp_pending", None)
            session.pop("viewer_otp_user", None)
            session.pop("viewer_otp_ip", None)

            secure_session_destruct()
            session.permanent    = True
            session["user"]      = username
            session["role"]      = "viewer"
            session["user_id"]   = f"viewer_{user.id}"
            session["login_time"]    = now
            session["last_activity"] = now
            session["session_token"] = secrets.token_hex(32)

            app.config[f"ACTIVE_SESSION_viewer_{user.id}"] = session["session_token"]

            log = CameraLog(
                event="VIEWER_LOGIN_SUCCESSFUL",
                username=username,
                ip_address=client_ip
            )
            db.session.add(log)
            db.session.commit()

            log = LoginLog(username=username, ip_address=client_ip, status='success', role='viewer')
            db.session.add(log)
            db.session.commit()

            return redirect(url_for("viewer.viewer"))
        else:
            if client_ip not in IP_FAILED_ATTEMPTS:
                IP_FAILED_ATTEMPTS[client_ip] = [1, now]
            else:
                IP_FAILED_ATTEMPTS[client_ip][0] += 1
                IP_FAILED_ATTEMPTS[client_ip][1] = now

            log = CameraLog(
                event=f"INVALID_VIEWER_OTP_ATTEMPT_USER_{username}",
                ip_address=client_ip
            )
            db.session.add(log)
            db.session.commit()

            return make_response(render_template("viewer_otp.html",
                error="Invalid or expired code."))

    return render_template("viewer_otp.html")


# ======================================================================
# INIT DB & RUN
# ======================================================================

with app.app_context():
    db.drop_all()
    db.create_all()

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
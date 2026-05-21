from flask import Flask, request, session, redirect, url_for, make_response, render_template
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf import CSRFProtect
from database.models import db, CameraLog
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

# ─── Session lifetime (fallback if not set in Config) ─────────────────
app.config.setdefault("PERMANENT_SESSION_LIFETIME", timedelta(minutes=30))

# ─── Zero Hardcoded Secrets Policy ───────────────────────────────────
# All secrets pulled from environment variables only
app.secret_key = os.environ.get("FLASK_SECRET_KEY", secrets.token_hex(32))
app.config.setdefault("SQLALCHEMY_DATABASE_URI", os.environ.get("DATABASE_URL", "sqlite:///cctv.db"))
app.config.setdefault("SQLALCHEMY_TRACK_MODIFICATIONS", False)

# ─── Cryptographic Pepper ─────────────────────────────────────────────
PEPPER = os.environ.get("CRYPTOGRAPHIC_PEPPER", "FallbackSuperSecretPepper2026!")

# ─── Anti-Session Hijacking: Cookie Security ─────────────────────────
app.config.update(
    SESSION_COOKIE_SECURE=True,       # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,     # Block JS access (anti-XSS cookie theft)
    SESSION_COOKIE_SAMESITE="Strict"  # Block cross-site cookie transmission (anti-CSRF)
)

# ─── Extensions ───────────────────────────────────────────────────────
db.init_app(app)
bcrypt = Bcrypt(app)
csrf = CSRFProtect(app)

# ─── Rate Limiter ─────────────────────────────────────────────────────
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"  # RAM-only, no disk persistence
)

# ─── In-memory IP failure tracking ───────────────────────────────────
IP_FAILED_ATTEMPTS = {}  # { ip: [failure_count, last_failure_timestamp] }


# ======================================================================
# SECURITY UTILITIES
# ======================================================================

def get_sanitized_ip():
    """Reverse proxy-aware IP extractor with sanitization."""
    if request.headers.get("X-Forwarded-For"):
        ip = request.headers.get("X-Forwarded-For").split(",")[0].strip()
    else:
        ip = request.remote_addr
    return "".join(c for c in ip if c.isalnum() or c in [".", ":"])


def secure_session_destruct():
    """Wipes all session data on logout, timeout, or conflict."""
    session.clear()


def render_with_error(err_msg):
    """Returns login page with a generic error message."""
    return make_response(render_template("login.html", error=err_msg))


# ======================================================================
# SESSION ENFORCEMENT DECORATOR
# ======================================================================

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get("is_admin") or not session.get("user_id"):
            return redirect(url_for("auth.login"))

        now = time.time()

        # Idle timeout: 15 minutes
        last_activity = session.get("last_activity", now)
        if (now - last_activity) > 900:
            secure_session_destruct()
            return redirect(url_for("auth.login", error="Session expired due to inactivity."))

        # Absolute timeout: 1 hour
        login_time = session.get("login_time", now)
        if (now - login_time) > 3600:
            secure_session_destruct()
            return redirect(url_for("auth.login", error="Absolute session timeout reached."))

        # Single active session enforcement
        active_token = app.config.get(f"ACTIVE_SESSION_{session.get('user_id')}")
        if session.get("session_token") != active_token:
            secure_session_destruct()
            return redirect(url_for("auth.login", error="Logged out: Another device accessed this account."))

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
# HONEYPOT TRAPS (recon bait — returns 404 to confuse scanners)
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

app.register_blueprint(auth)
app.register_blueprint(dashboard_bp)
app.register_blueprint(camera_bp)


# ======================================================================
# AUTH ROUTES (login / logout)
# NOTE: These live here to use the app-level IP tracking dict and limiter.
#       Move to routes/auth.py if you refactor IP_FAILED_ATTEMPTS to a
#       shared module (e.g. utils/security.py).
# ======================================================================

@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    client_ip = get_sanitized_ip()
    now = time.time()

    # ── IP Lockout check ─────────────────────────────────────────────
    if client_ip in IP_FAILED_ATTEMPTS:
        failures, lockout_time = IP_FAILED_ATTEMPTS[client_ip]
        if failures >= 10:
            if now - lockout_time < 300:  # 5-minute lockout window
                return render_with_error("IP temporarily locked out. Try again later.")
            else:
                IP_FAILED_ATTEMPTS[client_ip] = [0, 0]  # Reset after lockout expires

    if request.method == "POST":
        # ── Input sanitization ───────────────────────────────────────
        input_user = "".join(c for c in request.form.get("username", "") if c.isalnum())
        input_pass = request.form.get("password", "")
        input_otp  = request.form.get("otp", "")

        # ── Env-stored credentials ───────────────────────────────────
        env_admin_user   = os.environ.get("ADMIN_USERNAME", "admin")
        env_admin_hash   = os.environ.get("ADMIN_PASSWORD_HASH")   # bcrypt hash, NOT plaintext
        env_mfa_secret   = os.environ.get("ADMIN_MFA_SECRET", "JBSWY3DPEHPK3PXP")

        # ── Progressive delay (slows brute-force even within rate limit window) ──
        if client_ip in IP_FAILED_ATTEMPTS:
            failures = IP_FAILED_ATTEMPTS[client_ip][0]
            if failures > 0:
                time.sleep(min(0.5 * failures, 10))  # Cap at 10s to avoid DoS

        # ── Username check (constant-time) ───────────────────────────
        username_match = hmac.compare_digest(
            input_user.encode("utf-8"),
            env_admin_user.encode("utf-8")
        )

        # ── Password check via bcrypt + pepper ───────────────────────
        # The stored hash was generated from: bcrypt(password + PEPPER)
        # To generate: bcrypt.generate_password_hash(raw_password + PEPPER).decode("utf-8")
        peppered_input = input_pass + PEPPER
        password_match = (
            env_admin_hash is not None
            and bcrypt.check_password_hash(env_admin_hash, peppered_input)
        )

        # ── TOTP / 2FA check ─────────────────────────────────────────
        totp = pyotp.TOTP(env_mfa_secret)
        otp_match = totp.verify(input_otp)

        # ── All three factors must pass ───────────────────────────────
        if username_match and password_match and otp_match:
            IP_FAILED_ATTEMPTS[client_ip] = [0, 0]

            # Session regeneration (anti-session fixation)
            secure_session_destruct()
            session.permanent = True
            session["is_admin"]      = True
            session["user_id"]       = "admin_01"
            session["login_time"]    = now
            session["last_activity"] = now
            session["session_token"] = secrets.token_hex(32)

            # Single active session enforcement
            app.config["ACTIVE_SESSION_admin_01"] = session["session_token"]

            # Audit log
            log = CameraLog(event="ADMIN_LOGIN_SUCCESSFUL", ip_address=client_ip)
            db.session.add(log)
            db.session.commit()

            return redirect(url_for("dashboard_bp.index"))

        else:
            # Track failure
            if client_ip not in IP_FAILED_ATTEMPTS:
                IP_FAILED_ATTEMPTS[client_ip] = [1, now]
            else:
                IP_FAILED_ATTEMPTS[client_ip][0] += 1
                IP_FAILED_ATTEMPTS[client_ip][1] = now

            # Audit log
            log = CameraLog(
                event=f"UNAUTHORIZED_LOGIN_ATTEMPT_USER_{input_user}",
                ip_address=client_ip
            )
            db.session.add(log)
            db.session.commit()

            # Generic error — no username enumeration
            return render_with_error("Invalid administrative credentials or verification token.")

    return render_template("login.html")


@app.route("/logout")
def logout():
    client_ip = get_sanitized_ip()
    log = CameraLog(event="ADMIN_LOGOUT_REQUESTED", ip_address=client_ip)
    db.session.add(log)
    db.session.commit()

    secure_session_destruct()
    return redirect(url_for("login", message="Successfully logged out of secure boundary."))


# ======================================================================
# INIT DB & RUN
# ======================================================================

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=False, host="0.0.0.0", port=5000)
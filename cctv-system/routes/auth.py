from flask import Blueprint, render_template, request, redirect, session, url_for, abort, current_app
from flask_bcrypt import Bcrypt
from database.models import db, User, LoginLog
from functools import wraps
from routes.logger import emit_secure_log
import pyotp
import qrcode
import io
import base64
import re

auth = Blueprint('auth', __name__)
bcrypt = Bcrypt()

# ─── Validators ────────────────────────────────────────────────────────────────
def is_valid_username(username):
    return re.match("^[a-zA-Z0-9_]{3,50}$", username) is not None

# ─── Decorators ────────────────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get("role") != "admin":
            abort(403)
        return f(*args, **kwargs)
    return decorated

# ─── Routes ────────────────────────────────────────────────────────────────────

# NOTE: "/" and "/login" and "/logout" are handled in app.py
# This blueprint only handles /register

@auth.route("/register", methods=["GET", "POST"])
@login_required
@admin_required
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        ip_address = request.remote_addr
        admin_user = session.get("user")

        if not is_valid_username(username):
            emit_secure_log(
                'ADMIN_REGISTER_FAILED',
                f"Admin '{admin_user}' tried to register invalid username '{username}'.",
                ip_address=ip_address
            )
            return redirect(url_for("dashboard.dashboard",
                register_error="Invalid username. Use 3-50 letters, numbers, or underscores."))

        if len(password) < 8:
            emit_secure_log(
                'ADMIN_REGISTER_FAILED',
                f"Admin '{admin_user}' tried to register '{username}' with a short password.",
                ip_address=ip_address
            )
            return redirect(url_for("dashboard.dashboard",
                register_error="Password must be at least 8 characters."))

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            emit_secure_log(
                'ADMIN_REGISTER_FAILED',
                f"Admin '{admin_user}' tried to register already-existing username '{username}'.",
                ip_address=ip_address
            )
            return redirect(url_for("dashboard.dashboard",
                register_error="Username already exists."))

        # ── Generate OTP secret for the new viewer ────────────────────
        otp_secret = pyotp.random_base32()
        totp = pyotp.TOTP(otp_secret)
        otp_uri = totp.provisioning_uri(name=username, issuer_name="CCTV Monitor")

        # Generate QR code as base64 PNG
        qr = qrcode.make(otp_uri)
        buffer = io.BytesIO()
        qr.save(buffer, format="PNG")
        qr_b64 = base64.b64encode(buffer.getvalue()).decode("utf-8")

        # ── Hash password with pepper ─────────────────────────────────
        pepper = current_app.config.get("PEPPER", "FallbackSuperSecretPepper2026!")
        peppered_password = password + pepper
        hashed_password = bcrypt.generate_password_hash(peppered_password).decode("utf-8")
        new_user = User(username=username, password=hashed_password, role="viewer", otp_secret=otp_secret)
        db.session.add(new_user)
        db.session.commit()

        emit_secure_log(
            'ADMIN_REGISTERED_USER',
            f"Admin '{admin_user}' successfully registered new user '{username}'.",
            ip_address=ip_address
        )

        # Redirect to register_success page with QR code
        return render_template("register_success.html",
            username=username,
            qr_code=qr_b64,
            otp_secret=otp_secret
        )

    return redirect(url_for("dashboard.dashboard"))
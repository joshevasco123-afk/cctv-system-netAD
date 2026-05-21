from flask import Blueprint, render_template, request, redirect, session, url_for, abort
from flask_bcrypt import Bcrypt
from database.models import db, User, LoginLog
from functools import wraps
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
            return redirect(url_for("auth.home"))
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
@auth.route("/")
def home():
    return render_template("login.html", error=False)

@auth.route("/login", methods=["POST"])
def login():
    from app import limiter
    from logger import emit_secure_log
    limiter.limit("5 per minute")(lambda: None)()

    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    ip_address = request.remote_addr

    if not username or not password:
        return render_template("login.html", error=True), 401

    user = User.query.filter_by(username=username).first()

    if user and bcrypt.check_password_hash(user.password, password):
        session.clear()
        session.permanent = True
        session["user"] = username
        session["role"] = user.role

        log = LoginLog(username=username, ip_address=ip_address, status="success")
        db.session.add(log)
        db.session.commit()

        # Log successful login
        event = 'ADMIN_LOGIN_SUCCESS' if user.role == 'admin' else 'USER_LOGIN_SUCCESS'
        emit_secure_log(event, f"User '{username}' logged in successfully.", ip_address=ip_address)

        if user.role == "admin":
            return redirect(url_for("dashboard.dashboard"))
        else:
            return redirect(url_for("dashboard.viewer_dashboard"))

    # Failed login
    log = LoginLog(username=username, ip_address=ip_address, status="failed")
    db.session.add(log)
    db.session.commit()

    # Check for brute force: 3+ failed logins from same IP today
    from datetime import datetime, date
    today_start = datetime.combine(date.today(), datetime.min.time())
    from sqlalchemy import func
    failed_count = LoginLog.query.filter(
        LoginLog.ip_address == ip_address,
        LoginLog.status == 'failed',
        LoginLog.timestamp >= today_start
    ).count()

    if failed_count >= 3:
        emit_secure_log(
            'LOGIN_BRUTE_FORCE_SUSPECTED',
            f"IP {ip_address} has {failed_count} failed login attempts today. Username tried: '{username}'.",
            ip_address=ip_address
        )
    else:
        emit_secure_log(
            'LOGIN_FAILED',
            f"Failed login attempt for username '{username}'.",
            ip_address=ip_address
        )

    return render_template("login.html", error=True), 401

# ─── Register: admin only ──────────────────────────────────────────────────────
@auth.route("/register", methods=["GET", "POST"])
@login_required
@admin_required
def register():
    from logger import emit_secure_log
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

        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
        new_user = User(username=username, password=hashed_password, role="viewer")
        db.session.add(new_user)
        db.session.commit()

        emit_secure_log(
            'ADMIN_REGISTERED_USER',
            f"Admin '{admin_user}' successfully registered new user '{username}'.",
            ip_address=ip_address
        )
        return redirect(url_for("dashboard.dashboard",
            register_success=f"User '{username}' created successfully."))

    return redirect(url_for("dashboard.dashboard"))

# ─── Logout ────────────────────────────────────────────────────────────────────
@auth.route("/logout", methods=["POST"])
def logout():
    from logger import emit_secure_log
    username = session.get("user", "unknown")
    ip_address = request.remote_addr
    emit_secure_log(
        'ADMIN_LOGOUT',
        f"User '{username}' logged out.",
        ip_address=ip_address
    )
    session.clear()
    return redirect(url_for("auth.home"))
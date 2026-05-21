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
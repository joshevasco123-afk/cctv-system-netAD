from flask import Blueprint, render_template, session, redirect, url_for
from functools import wraps
import time
import secrets

viewer_bp = Blueprint('viewer', __name__)

def viewer_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user") or session.get("role") != "viewer":
            return redirect(url_for("viewer_login"))

        from app import app

        now = time.time()

        # 15 min inactivity timeout
        last_activity = session.get("last_activity", now)
        if (now - last_activity) > 900:
            session.clear()
            return redirect(url_for("viewer_login"))

        # 1 hour absolute session timeout
        login_time = session.get("login_time", now)
        if (now - login_time) > 3600:
            session.clear()
            return redirect(url_for("viewer_login"))

        # Single session token enforcement
        active_token = app.config.get(f"ACTIVE_SESSION_{session.get('user_id')}")
        if session.get("session_token") != active_token:
            session.clear()
            return redirect(url_for("viewer_login"))

        session["last_activity"] = now
        return f(*args, **kwargs)
    return decorated

@viewer_bp.route("/viewer")
@viewer_login_required
def viewer():
    return render_template("viewer.html", username=session.get("user"))
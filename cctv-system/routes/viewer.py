from flask import Blueprint, render_template, session, redirect, url_for, current_app, jsonify
from functools import wraps
import time

viewer_bp = Blueprint('viewer', __name__)


def viewer_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user") or session.get("role") != "viewer":
            return redirect(url_for("viewer_login"))

        now = time.time()

        last_activity = session.get("last_activity", now)
        if (now - last_activity) > 900:
            session.clear()
            return redirect(url_for("viewer_login"))

        login_time = session.get("login_time", now)
        if (now - login_time) > 3600:
            session.clear()
            return redirect(url_for("viewer_login"))

        active_token = current_app.config.get(f"ACTIVE_SESSION_{session.get('user_id')}")
        if session.get("session_token") != active_token:
            session.clear()
            return redirect(url_for("viewer_login"))

        from flask import request
        from database.models import BlockedIP
        raw_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
        client_ip = "".join(c for c in raw_ip.split(",")[0].strip() if c.isalnum() or c in [".", ":"])
        if BlockedIP.query.filter_by(ip_address=client_ip).first():
            session.clear()
            return redirect(url_for("viewer_login"))
        session["last_activity"] = now
        return f(*args, **kwargs)
    return decorated


@viewer_bp.route("/viewer")
@viewer_login_required
def viewer():
    return render_template("viewer.html", username=session.get("user"))



from flask import Blueprint, render_template, session, redirect, url_for, current_app, jsonify
from functools import wraps
from routes.camera import frame_store   # ← updated: uses frame_store, not camera_manager
import base64
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

        from app import is_ip_blocked, get_sanitized_ip
        if is_ip_blocked(get_sanitized_ip()):
            session.clear()
            return redirect(url_for("viewer_login"))
        session["last_activity"] = now
        return f(*args, **kwargs)
    return decorated


@viewer_bp.route("/viewer")
@viewer_login_required
def viewer():
    return render_template("viewer.html", username=session.get("user"))


@viewer_bp.route("/viewer_frame")
@viewer_login_required
def viewer_frame():
    """
    Returns the latest pushed frame as base64 JSON.
    Reads from frame_store (push-based) — no cap, no cv2, no freezing.
    """
    frame_bytes, _ = frame_store.get_frame_and_seq()

    if frame_bytes is None or not frame_store.is_fresh(stale_after=10):
        return jsonify({'ok': False, 'frame': None}), 503

    b64 = base64.b64encode(frame_bytes).decode('utf-8')
    return jsonify({'ok': True, 'frame': b64})
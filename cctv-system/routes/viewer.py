from flask import Blueprint, render_template, session, redirect, url_for, current_app, jsonify
from functools import wraps
from routes.camera import camera_manager
import time
import secrets

viewer_bp = Blueprint('viewer', __name__)

def viewer_login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user") or session.get("role") != "viewer":
            return redirect(url_for("viewer_login"))

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
        active_token = current_app.config.get(f"ACTIVE_SESSION_{session.get('user_id')}")
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

@viewer_bp.route("/viewer_frame")
@viewer_login_required
def viewer_frame():
    """Returns the latest camera frame as base64 JSON for viewer polling."""
    import cv2
    import base64

    try:
        with camera_manager._lock:
            if camera_manager.cap is None or not camera_manager.cap.isOpened():
                return jsonify({'ok': False, 'frame': None}), 503
            success, frame = camera_manager.cap.read()

        if not success or frame is None or frame.size == 0:
            return jsonify({'ok': False, 'frame': None}), 503

        ret, buffer = cv2.imencode('.jpg', frame)
        if not ret:
            return jsonify({'ok': False, 'frame': None}), 503

        b64 = base64.b64encode(buffer.tobytes()).decode('utf-8')
        return jsonify({'ok': True, 'frame': b64})

    except Exception:
        return jsonify({'ok': False, 'frame': None}), 503
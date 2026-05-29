from flask import Blueprint, Response, request, session, abort, current_app, jsonify
from database.models import db, CameraLog
from functools import wraps
import threading
import time
import os
import secrets
import base64
from datetime import datetime

camera_bp = Blueprint('camera', __name__)

class FrameStore:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance.latest_frame  = None
                cls._instance.frame_seq     = 0
                cls._instance.frame_lock    = threading.Lock()
                cls._instance.last_push_at  = 0
                cls._instance.active_token  = None
        return cls._instance

    def store_frame(self, jpeg_bytes):
        with self.frame_lock:
            self.latest_frame = jpeg_bytes
            self.frame_seq   += 1
            self.last_push_at = time.time()

    def get_frame_and_seq(self):
        with self.frame_lock:
            return self.latest_frame, self.frame_seq

    def is_fresh(self, stale_after=5):
        return (time.time() - self.last_push_at) < stale_after


frame_store = FrameStore()

# ── Rate-limit state for /viewer_frame (max 1 response/sec) ──
_viewer_frame_lock      = threading.Lock()
_last_viewer_frame_time = 0.0
_cached_viewer_response = None   # (encoded_str, seq)


def secure_admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin') or not session.get('user_id'):
            return abort(403, description="Access Denied: Unauthenticated Session")

        login_time = session.get('login_time')
        if not login_time or (time.time() - login_time) > 900:
            session.clear()
            return abort(401, description="Session Expired: Re-authentication Required")

        active_system_token = current_app.config.get(f"ACTIVE_SESSION_{session.get('user_id')}")
        if session.get('session_token') != active_system_token:
            return abort(401, description="Session Invalidated: Concurrent Admin Login Detected")

        return f(*args, **kwargs)
    return decorated_function


def get_validated_client_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
    cleaned_ip = "".join(c for c in ip if c.isalnum() or c in ['.', ':'])
    return cleaned_ip if cleaned_ip else "UNKNOWN_PROXIED_IP"


@camera_bp.route('/push_frame', methods=['POST'])
def push_frame():
    expected_secret = os.environ.get('PUSH_SECRET', '')
    incoming_secret = request.headers.get('X-Push-Secret', '')

    if not expected_secret or incoming_secret != expected_secret:
        return jsonify({'error': 'unauthorized'}), 403

    jpeg_bytes = request.data
    if not jpeg_bytes:
        return jsonify({'error': 'empty frame'}), 400

    frame_store.store_frame(jpeg_bytes)
    return jsonify({'ok': True, 'seq': frame_store.frame_seq}), 200


def generate_secure_frames(validated_token, username):
    last_seq          = -1
    no_frame_timeout  = 15
    disconnect_logged = False

    try:
        while True:
            if frame_store.active_token != validated_token:
                break

            frame_bytes, current_seq = frame_store.get_frame_and_seq()

            if current_seq == last_seq or frame_bytes is None:
                if not frame_store.is_fresh(stale_after=no_frame_timeout):
                    break
                time.sleep(0.02)
                continue

            last_seq = current_seq
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

    except Exception:
        pass
    finally:
        if not disconnect_logged:
            try:
                log = CameraLog(
                    event='CAMERA_STREAM_STOPPED',
                    username=username,
                    description='Admin MJPEG stream ended',
                    ip_address='SERVER'
                )
                db.session.add(log)
                db.session.commit()
            except Exception:
                db.session.rollback()


@camera_bp.route('/request_stream_token', methods=['POST'])
@secure_admin_required
def request_stream_token():
    token = secrets.token_hex(32)
    frame_store.active_token = token
    return {"stream_token": token}, 200


@camera_bp.route('/video_feed')
@secure_admin_required
def secure_video_feed():
    token_param = request.args.get('token')
    if not token_param or token_param != frame_store.active_token:
        return abort(403, description="Forbidden: Invalid or Expired Stream Token")

    client_ip = get_validated_client_ip()
    username  = session.get('user', 'unknown')

    try:
        log = CameraLog(
            event='CAMERA_STREAM_STARTED',
            username=username,
            description=f'Live stream opened by {username}',
            ip_address=client_ip
        )
        db.session.add(log)
        db.session.commit()
    except Exception:
        db.session.rollback()

    response = Response(
        generate_secure_frames(token_param, username),
        mimetype='multipart/x-mixed-replace; boundary=frame'
    )
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
    response.headers["Pragma"]        = "no-cache"
    response.headers["Expires"]       = "0"
    response.headers["X-Frame-Options"]         = "DENY"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
    return response


@camera_bp.route('/viewer_frame')
def viewer_frame():
    global _last_viewer_frame_time, _cached_viewer_response

    # Allow both admin and viewer sessions
    is_admin  = session.get('is_admin') and session.get('user_id')
    is_viewer = session.get('user') and session.get('role') == 'viewer'

    if not is_admin and not is_viewer:
        return jsonify({'error': 'unauthorized'}), 403

    now = time.time()

    with _viewer_frame_lock:
        # If called faster than 1/sec, return cached response
        if now - _last_viewer_frame_time < 1.0 and _cached_viewer_response is not None:
            encoded, seq = _cached_viewer_response
            return jsonify({'ok': True, 'available': True, 'frame': encoded, 'seq': seq}), 200

        frame_bytes, seq = frame_store.get_frame_and_seq()

        if frame_bytes is None or not frame_store.is_fresh(stale_after=10):
            return jsonify({'ok': False, 'available': False}), 200

        encoded = base64.b64encode(frame_bytes).decode('utf-8')
        _last_viewer_frame_time = now
        _cached_viewer_response = (encoded, seq)

    return jsonify({'ok': True, 'available': True, 'frame': encoded, 'seq': seq}), 200
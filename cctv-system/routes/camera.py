from flask import Blueprint, Response, request, session, abort, current_app, jsonify
from database.models import db, CameraLog
from functools import wraps
import cv2
import threading
import time
import os
import secrets
import base64
from datetime import datetime

camera_bp = Blueprint('camera', __name__)

# =====================================================================
# HARDENING MODULE II: Thread-Safe Singleton Pattern & Concurrency Lock
# =====================================================================
class SecureCameraSingleton:
    _instance = None
    _lock = threading.Lock()

    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super(SecureCameraSingleton, cls).__new__(cls)
                cls._instance.cap = None
                cls._instance.is_running = False
                cls._instance.active_token = None
                cls._instance.last_frame_time = 0
                cls._instance.active_username = None

                # ── Frame Buffer ──────────────────────────────────────
                # latest_frame  : raw JPEG bytes of the most recent frame
                # frame_seq     : counter incremented every time a new frame arrives
                # frame_lock    : protects latest_frame + frame_seq reads/writes
                cls._instance.latest_frame = None
                cls._instance.frame_seq    = 0
                cls._instance.frame_lock   = threading.Lock()

                # buffer thread state
                cls._instance._buffer_thread  = None
                cls._instance._buffer_running = False
        return cls._instance

    # ------------------------------------------------------------------
    def initialize_camera(self, username=None):
        # Control 3 / 10: Camera Index Whitelisting & Source Path Obfuscation
        raw_index  = os.environ.get('HARDWARE_CAMERA_INDEX', '0')
        camera_index = int(raw_index) if raw_index.isdigit() else raw_index

        if isinstance(camera_index, str) and camera_index.startswith('http'):
            stream_url = camera_index + ("&" if "?" in camera_index else "?") + "ngrok-skip-browser-warning=true"
        elif isinstance(camera_index, str) and camera_index.startswith('rtsp'):
            stream_url = camera_index
        else:
            stream_url = camera_index

        if self.cap is None or not self.cap.isOpened():
            if isinstance(stream_url, str) and stream_url.startswith('rtsp'):
                self.cap = cv2.VideoCapture(stream_url, cv2.CAP_FFMPEG)
            else:
                self.cap = cv2.VideoCapture(stream_url)
            self.cap.set(cv2.CAP_PROP_BUFFERSIZE, 1)   # Control 6
            self.is_running   = True
            self.last_frame_time = time.time()
            self.active_username = username

    def release_camera(self):
        # Control 5: Automated Resource Release
        # Does NOT stop the buffer thread — viewer feed stays alive
        if self.cap is not None:
            self.cap.release()
            self.cap = None
        self.is_running  = False
        self.active_token = None

    # ------------------------------------------------------------------
    # FRAME BUFFER: one background thread owns cap, writes frames + seq
    # ------------------------------------------------------------------
    def _buffer_loop(self):
        fps_cap    = 15
        frame_delay = 1.0 / fps_cap

        while self._buffer_running:
            start = time.time()

            with self._lock:
                if self.cap is None or not self.cap.isOpened():
                    time.sleep(0.3)
                    continue
                success, frame = self.cap.read()

            if not success or frame is None or frame.size == 0:
                time.sleep(0.05)
                continue

            # Control 8: Blank frame guard
            if cv2.mean(frame)[0] < 2.0:
                time.sleep(0.05)
                continue

            # Control 9: Timestamp overlay
            server_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            cv2.putText(frame, f"LIVE SERVER TIME: {server_time}", (10, 30),
                        cv2.FONT_HERSHEY_SIMPLEX, 0.7, (0, 255, 255), 2, cv2.LINE_AA)

            ret, buffer = cv2.imencode('.jpg', frame)
            if not ret:
                continue

            # Atomically store new frame and bump sequence counter
            with self.frame_lock:
                self.latest_frame  = buffer.tobytes()
                self.frame_seq    += 1
                self.last_frame_time = time.time()

            # Control 6: FPS throttle
            elapsed = time.time() - start
            sleep_for = frame_delay - elapsed
            if sleep_for > 0:
                time.sleep(sleep_for)

    def start_buffer(self):
        """Start background frame buffer thread (idempotent)."""
        if self._buffer_running and self._buffer_thread and self._buffer_thread.is_alive():
            return
        self._buffer_running = True
        self._buffer_thread  = threading.Thread(target=self._buffer_loop, daemon=True)
        self._buffer_thread.start()

    def stop_buffer(self):
        self._buffer_running = False

    def get_frame_and_seq(self):
        """Return (jpeg_bytes, seq_number) atomically."""
        with self.frame_lock:
            return self.latest_frame, self.frame_seq

    def auto_start(self):
        """Auto-initialize camera + buffer on app startup."""
        def _start():
            time.sleep(3)
            try:
                with self._lock:
                    self.initialize_camera(username='system')
                self.start_buffer()
            except Exception:
                pass
        threading.Thread(target=_start, daemon=True).start()


camera_manager = SecureCameraSingleton()
camera_manager.auto_start()


# =====================================================================
# HARDENING MODULE I & VII: Auth & Session Decorators
# =====================================================================
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


# =====================================================================
# HARDENING MODULE XIII: Reverse Proxy Client-IP Validation
# =====================================================================
def get_validated_client_ip():
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
    cleaned_ip = "".join(c for c in ip if c.isalnum() or c in ['.', ':'])
    return cleaned_ip if cleaned_ip else "UNKNOWN_PROXIED_IP"


# =====================================================================
# HARDENING MODULE V: Admin MJPEG stream — sequence-number driven
# =====================================================================
def generate_secure_frames(validated_token, username):
    """
    MJPEG stream for admin dashboard.

    Tracks last_seq — only yields when frame_seq has changed.
    No Event race conditions; no spinning on the same frame.
    """
    last_seq          = -1
    no_frame_timeout  = 10   # seconds with no new frame before giving up
    last_new_frame_at = time.time()
    disconnect_logged = False

    try:
        while True:
            # Control 2: token check per iteration
            if camera_manager.active_token != validated_token:
                break

            frame_bytes, current_seq = camera_manager.get_frame_and_seq()

            if current_seq == last_seq or frame_bytes is None:
                # No new frame yet — sleep briefly and check again
                if (time.time() - last_new_frame_at) > no_frame_timeout:
                    break
                time.sleep(0.02)   # 20ms poll — tight enough, no spin-burn
                continue

            # New frame arrived
            last_seq          = current_seq
            last_new_frame_at = time.time()

            # Control 7: MJPEG boundary delivery
            yield (b'--frame\r\n'
                   b'Content-Type: image/jpeg\r\n\r\n' + frame_bytes + b'\r\n')

    except Exception:
        pass
    finally:
        # Do NOT release camera — buffer keeps running for viewers
        if not disconnect_logged:
            try:
                log = CameraLog(
                    event='CAMERA_STREAM_STOPPED',
                    username=username,
                    description='Admin MJPEG stream ended — buffer still active for viewers',
                    ip_address='SERVER'
                )
                db.session.add(log)
                db.session.commit()
            except Exception:
                db.session.rollback()


# =====================================================================
# CORE SECURED ROUTE ENDPOINTS
# =====================================================================
@camera_bp.route('/request_stream_token', methods=['POST'])
@secure_admin_required
def request_stream_token():
    token = secrets.token_hex(32)
    camera_manager.active_token = token
    with camera_manager._lock:
        camera_manager.initialize_camera(username=session.get('user', 'admin'))
    camera_manager.start_buffer()
    return {"stream_token": token}, 200


@camera_bp.route('/video_feed')
@secure_admin_required
def secure_video_feed():
    token_param = request.args.get('token')
    if not token_param or token_param != camera_manager.active_token:
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

    with camera_manager._lock:
        camera_manager.initialize_camera(username=username)
    camera_manager.start_buffer()

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


# =====================================================================
# VIEWER FRAME ENDPOINT — polls latest frame from shared buffer
# =====================================================================
@camera_bp.route('/viewer_frame')
def viewer_frame():
    """
    Viewer polls this every ~150ms for the latest frame as base64 JSON.
    Reads from the shared buffer — never touches cap directly.
    """
    if not session.get('user') or session.get('role') != 'viewer':
        return jsonify({'error': 'unauthorized'}), 403

    frame_bytes, _ = camera_manager.get_frame_and_seq()

    if frame_bytes is None:
        return jsonify({'available': False}), 200

    encoded = base64.b64encode(frame_bytes).decode('utf-8')
    return jsonify({'available': True, 'frame': encoded}), 200